#!/usr/bin/env python3
"""Control the dedicated VM over authenticated SSH + Apple VNC. No host input events.

Requires Remote Management enabled through the guest's Sharing UI for user ham.
Credentials stay in ~/.sentinel-lab/credentials.json, never command arguments/logs.
Run with: uv run --with asyncvnc==1.3.0 --with pillow python .../vm_control.py
"""
import argparse
import asyncio
import json
from pathlib import Path
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
        if args.key: client.keyboard.press(*args.key)
        if args.text: client.keyboard.write(args.text)
        if args.login_password: client.keyboard.write(settings['password'])
        if args.account_field:
            value = json.loads((Path.home()/'.sentinel-lab/meeting-accounts.json').read_text())
            for part in args.account_field.split('.'):
                value = value[part]
            if not isinstance(value, str) or not value:
                raise ValueError('Requested account field is not configured')
            # Only use after inspecting the intended guest field. Never echo values.
            client.keyboard.write(value)
        await client.drain()
        if args.click or args.move or args.drag or args.key or args.text or args.login_password or args.account_field:
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
    p.add_argument('--move',type=int,nargs=2,metavar=('X','Y'),help='Hover without clicking (for native share pickers)')
    p.add_argument('--drag',type=int,nargs=4,metavar=('X1','Y1','X2','Y2'),help='Drag to arrange guest windows')
    p.add_argument('--key',nargs='+')
    p.add_argument('--text',help='Synthetic non-secret test text only')
    p.add_argument('--login-password',action='store_true',help='Type saved guest password into an already inspected authentication field')
    p.add_argument('--account-field', choices=[
        f'{service}.{role}.{field}'
        for service in ['zoom', 'google_meet', 'microsoft_teams']
        for role in ['host', 'receiver'] for field in ['email', 'password']
    ] + [f'{service}.meeting_url' for service in ['zoom', 'google_meet', 'microsoft_teams']] + ['zoom.meeting_passcode'],
        help='Type a saved test-account field without putting its value in command arguments')
    args=p.parse_args()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    tunnel=subprocess.Popen(['ssh','-F',str(Path.home()/'.sentinel-lab/ssh_config'),'-oBatchMode=yes',
                             '-oExitOnForwardFailure=yes','-N','-L',f'127.0.0.1:{port}:127.0.0.1:5900','boxcop-lab'],
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
