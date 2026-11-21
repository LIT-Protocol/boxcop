"""Build the pinned, statically linked inference engine shipped inside BoxCop."""
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
import tarfile

REVISION = '7071ba378afa96dcd69c41e1ec2b4912364dbee4'
SOURCE_SHA256 = '93d453d0ad99853b9f1dafeea78fa55da9a838ba71804abcf1aa823537703b79'
URL = f'https://codeload.github.com/ggml-org/llama.cpp/tar.gz/{REVISION}'
# Exit even after an uncatchable sidecar crash/kill; never leave an orphan model server.
MAIN = '''#include <unistd.h>
#include <thread>
#include <chrono>
int llama_server(int argc, char ** argv);
int main(int argc, char ** argv) {
    const auto parent = getppid();
    if (parent == 1) return 1;
    std::thread([parent] {
        while (getppid() == parent) std::this_thread::sleep_for(std::chrono::seconds(1));
        _exit(0);
    }).detach();
    return llama_server(argc, argv);
}
'''


def bundle_runtime(destination, work, run):
    archive = work / 'llama-source.tar.gz'
    run(['/usr/bin/curl', '--disable', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
         '--max-time', '120', '--output', archive, URL])
    if sha256(archive.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError('Inference runtime source checksum mismatch')
    with tarfile.open(archive) as source:
        source.extractall(work, filter='data')
    source = work / ('llama.cpp-' + REVISION)
    (source / 'tools/server/main.cpp').write_text(MAIN)
    build = work / 'inference-build'
    run(['cmake', '-S', source, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_OSX_DEPLOYMENT_TARGET=14.0', '-DBUILD_SHARED_LIBS=OFF',
         '-DGGML_NATIVE=OFF', '-DGGML_METAL_EMBED_LIBRARY=ON', '-DLLAMA_OPENSSL=OFF',
         '-DLLAMA_BUILD_TESTS=OFF', '-DLLAMA_BUILD_EXAMPLES=OFF', '-DLLAMA_BUILD_APP=OFF',
         '-DLLAMA_BUILD_UI=OFF', '-DLLAMA_USE_PREBUILT_UI=OFF', '-DLLAMA_BUILD_SERVER=ON'])
    run(['cmake', '--build', build, '--target', 'llama-server', '-j', '4'], timeout=1200)
    destination.mkdir(parents=True)
    binary = destination / 'llama-server'
    shutil.copy2(build / 'bin/llama-server', binary)
    # Static ggml/llama linkage prevents accidental Homebrew/library dependencies.
    linked = subprocess.check_output(['/usr/bin/otool', '-L', binary], text=True)
    for line in linked.splitlines()[1:]:
        if not line.strip().startswith(('/System/Library/', '/usr/lib/')):
            raise ValueError('Unbundled inference dependency: ' + line.strip())
    shutil.copy2(source / 'LICENSE', destination / 'llama.cpp-LICENSE')
    shutil.copytree(source / 'licenses', destination / 'licenses')
    (destination / 'BUILD.txt').write_text(f'llama.cpp {REVISION}\nSource SHA256 {SOURCE_SHA256}\nBoxCop parent-process watchdog added to main.cpp.\n')
