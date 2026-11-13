#!/usr/bin/env python3
"""Control the lab VM over authenticated SSH and Apple VNC. Sends no input to the host.

Requires Remote Management enabled for the guest user in the guest's Sharing settings.
Credentials stay in ~/.sentinel-lab/credentials.json and never appear in arguments or logs.
The lab directory and its SSH alias keep their original names; see docs/vm-lab.md.
Run with: uv run --with asyncvnc==1.3.0 --with pillow python desktop/macos/scripts/vm_control.py
"""
import argparse
import asyncio
import json
from pathlib import Path
import re
import socket
import subprocess
import time
import asyncvnc
from PIL import Image

async def control(args, port):
    settings = json.loads((Path.home()/'.sentinel-lab/credentials.json').read_text())
    async with asyncvnc.connect('127.0.0.1', port=port, username=settings['username'], password=settings['password']) as client:
        pixels = await client.screenshot()
        # Never click blindly when macOS denies capture/control.
        if not pixels[:, :, :3].any():
            raise RuntimeError('VM returned a black screen; enable Remote Management in guest Sharing settings')
        if args.click or args.move:
            x,y=args.click or args.move
            if not (0 <= x < pixels.shape[1] and 0 <= y < pixels.shape[0]): raise ValueError('Click outside screen')
            client.mouse.move(x,y)
            await client.drain()
            await asyncio.sleep(.1)
            if args.click:
                with client.mouse.hold():
                    await client.drain()
                    await asyncio.sleep(.1)
        if args.drag:
            x1, y1, x2, y2 = args.drag
            for x, y in [(x1, y1), (x2, y2)]:
                if not (0 <= x < pixels.shape[1] and 0 <= y < pixels.shape[0]):
                    raise ValueError('Drag outside screen')
            client.mouse.move(x1, y1)
            await client.drain()
            with client.mouse.hold():
                await client.drain()
                await asyncio.sleep(.2)
                for step in range(1, 11):
                    client.mouse.move(round(x1 + (x2-x1)*step/10), round(y1 + (y2-y1)*step/10))
                    await client.drain()
                    await asyncio.sleep(.05)
        if args.scroll:
            for _ in range(abs(args.scroll)):
                (client.mouse.scroll_down if args.scroll > 0 else client.mouse.scroll_up)()
                await client.drain()
                await asyncio.sleep(.005)
        if args.key: client.keyboard.press(*args.key)
        if args.text: client.keyboard.write(args.text)
        if args.login_password: client.keyboard.write(settings['password'])
        await client.drain()
        if args.click or args.move or args.drag or args.scroll or args.key or args.text or args.login_password:
            await asyncio.sleep(.5)
            pixels=await client.screenshot()
        if args.screenshot:
            args.screenshot.parent.mkdir(parents=True,exist_ok=True)
            Image.fromarray(pixels).save(args.screenshot)
        print(json.dumps({'width':pixels.shape[1],'height':pixels.shape[0],'screenshot':str(args.screenshot) if args.screenshot else None}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--screenshot',type=Path)
    p.add_argument('--click',type=int,nargs=2,metavar=('X','Y'))
    p.add_argument('--move',type=int,nargs=2,metavar=('X','Y'),help='Hover without clicking')
    p.add_argument('--drag',type=int,nargs=4,metavar=('X1','Y1','X2','Y2'),help='Drag to arrange guest windows')
    p.add_argument('--scroll',type=int,metavar='STEPS',help='Scroll at the pointer after --move; positive is down')
    p.add_argument('--key',nargs='+')
    p.add_argument('--text',help='Synthetic non-secret test text only')
    p.add_argument('--login-password',action='store_true',help='Type saved guest password into an already inspected authentication field')
    p.add_argument('--host',help='Guest IP address; by default ~/.sentinel-lab/lab finds it')
    args=p.parse_args()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    helper=Path.home()/'.sentinel-lab/lab'
    if not args.host and helper.exists():  # the helper finds the acceptance VM by its MAC address
        found=subprocess.run([str(helper),'ip'],capture_output=True,text=True)
        if found.returncode: raise SystemExit(found.stderr.strip() or 'the lab VM is not reachable')
        args.host=found.stdout.strip()
    if args.host and not re.fullmatch(r'[0-9A-Fa-f:.]+',args.host): raise SystemExit('--host must be an IP address')
    override=['-oHostName='+args.host] if args.host else []
    tunnel=subprocess.Popen(['ssh','-F',str(Path.home()/'.sentinel-lab/ssh_config'),'-oBatchMode=yes',*override,
                             '-oExitOnForwardFailure=yes','-N','-L',f'127.0.0.1:{port}:127.0.0.1:5900','sentinel-lab'],
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if tunnel.poll() is not None: raise RuntimeError('SSH tunnel failed')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1): break
            except OSError: time.sleep(.1)
        asyncio.run(asyncio.wait_for(control(args,port),20))
    finally:
        tunnel.terminate()
        try: tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired: tunnel.kill();tunnel.wait()

if __name__ == '__main__': main()
