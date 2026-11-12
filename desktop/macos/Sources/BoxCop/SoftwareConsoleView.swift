#if os(macOS)
import SwiftUI
import BoxCopCore

struct SoftwareConsoleSelection: Identifiable {
    let id: String
    let name: String
}

struct SoftwareConsoleView: View {
    let selection: SoftwareConsoleSelection
    let isActive: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var snapshot: SoftwareConsoleSnapshot?
    @State private var follow = true
    @State private var copied = false
    init(selection: SoftwareConsoleSelection, isActive: Bool = false, initialSnapshot: SoftwareConsoleSnapshot? = nil) {
        self.selection = selection; self.isActive = isActive
        _snapshot = State(initialValue: initialSnapshot)
    }
    private var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/software-console")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(selection.name) console").font(.title2.bold())
                    Text(snapshot.map { $0.status == "running" ? (isActive ? "Live output · refreshes every second" : "No completion recorded · checking for new output") : "Saved output · \($0.status.replacingOccurrences(of: "_", with: " "))" } ?? "Waiting for console output…")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            HStack {
                Toggle("Follow output", isOn: $follow).toggleStyle(.checkbox)
                Spacer()
                if ["ruby", "node", "brotli", "cloudflared"].contains(selection.name) {
                    Button("Open Homebrew build logs") {
                        let path = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Homebrew").appendingPathComponent(selection.name)
                        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path.path)
                    }.help("Homebrew saves detailed compiler output separately from its console summary.")
                }
                Button(copied ? "Copied" : "Copy output") {
                    NSPasteboard.general.clearContents()
                    copied = NSPasteboard.general.setString(snapshot?.text ?? "", forType: .string)
                }.disabled(snapshot?.text.isEmpty != false)
            }
            ScrollViewReader { proxy in
                ScrollView(.vertical) {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(snapshot?.text ?? "Output will appear here when the updater writes it. Runs started in older BoxCop builds have no saved console. Package managers may also pause output while compiling.")
                            .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Color.clear.frame(height: 1).id("end")
                    }.padding(12).frame(maxWidth: .infinity, alignment: .topLeading)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
                .onChange(of: snapshot?.updatedAt) { _ in
                    if follow { proxy.scrollTo("end", anchor: .bottom) }
                }
                .onChange(of: follow) { value in if value { proxy.scrollTo("end", anchor: .bottom) } }
            }
            if let last = snapshot?.updatedAt { Text("Last output: " + last).font(.caption).foregroundStyle(.secondary) }
            if snapshot?.truncated == true {
                Text("Showing the latest output; older lines were trimmed to keep the console bounded.").font(.caption).foregroundStyle(.secondary)
            }
            Text("Closing this console does not stop the update. Output stays on this Mac; copied output may contain local paths or other details.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(20).frame(minWidth: 700, idealWidth: 850, minHeight: 450, idealHeight: 600)
        .background(Color(nsColor: .windowBackgroundColor))
        .task(id: selection.id) {
            let id = selection.id, location = directory
            while !Task.isCancelled {
                let next = await Task.detached(priority: .utility) { SoftwareConsole.read(id: id, directory: location) }.value
                if let next { snapshot = next }
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { break }
            }
        }
    }
}
#endif
