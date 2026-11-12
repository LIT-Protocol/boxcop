#if os(macOS)
import AppKit

/// Run before constructing the model, updater, login item, or session owner.
@MainActor enum ApplicationInstall {
    static func prepareLaunch() -> Bool {
        let source = Bundle.main.bundleURL
        // SwiftPM tools and development bundles remain runnable in their checkout.
        guard source.pathExtension == "app",
              Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") != nil,
              source.deletingLastPathComponent().path != "/Applications" else { return true }
        let destination = URL(fileURLWithPath: "/Applications/BoxCop.app")
        let volume = diskImageVolume(containing: source)
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = volume == nil ? "Move BoxCop to Applications" : "BoxCop is running from the disk image"
        alert.informativeText = "Move it to Applications to continue. Your setup progress will be saved."
        let exists = FileManager.default.fileExists(atPath: destination.path)
        alert.addButton(withTitle: exists ? "Open BoxCop in Applications" : "Move to Applications")
        alert.addButton(withTitle: "Quit")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        do {
            if exists {
                guard Bundle(url: destination)?.bundleIdentifier == Bundle.main.bundleIdentifier else {
                    throw CocoaError(.fileWriteFileExists)
                }
            } else {
                // Stage on the destination volume so an interrupted copy never looks installed.
                let staging = destination.deletingLastPathComponent().appendingPathComponent(".BoxCop-install-\(UUID().uuidString).app")
                defer { try? FileManager.default.removeItem(at: staging) }
                try FileManager.default.copyItem(at: source, to: staging)
                try FileManager.default.moveItem(at: staging, to: destination)
            }
            // Arguments are data, not shell source. Wait until this copy exits before
            // opening the installed copy and detaching the source disk image.
            let helper = Process()
            helper.executableURL = URL(fileURLWithPath: "/bin/sh")
            helper.currentDirectoryURL = URL(fileURLWithPath: "/")
            helper.arguments = ["-c", "i=0; while /bin/kill -0 \"$1\" 2>/dev/null; do i=$((i+1)); [ \"$i\" -lt 100 ] || exit 1; /bin/sleep 0.2; done; /usr/bin/open \"$2\" || exit 1; if [ -n \"$3\" ]; then /usr/bin/hdiutil detach \"$3\"; fi", "boxcop-install", String(ProcessInfo.processInfo.processIdentifier), destination.path, volume ?? ""]
            try helper.run()
        } catch {
            let failure = NSAlert()
            failure.messageText = "BoxCop could not open from Applications"
            failure.informativeText = "Quit BoxCop, drag BoxCop.app into the Applications folder in Finder, then open BoxCop from Applications. If a copy is already there, open that copy. Your setup progress is saved."
            failure.addButton(withTitle: "Open Applications")
            failure.runModal()
            NSWorkspace.shared.open(destination.deletingLastPathComponent())
        }
        return false
    }

    private static func diskImageVolume(containing app: URL) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = ["info", "-plist"]
        let pipe = Pipe(); process.standardOutput = pipe
        do { try process.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let images = info["images"] as? [[String: Any]] else { return nil }
        return images.flatMap { $0["system-entities"] as? [[String: Any]] ?? [] }
            .compactMap { $0["mount-point"] as? String }
            .first { app.path.hasPrefix($0 + "/") }
    }
}
#endif
