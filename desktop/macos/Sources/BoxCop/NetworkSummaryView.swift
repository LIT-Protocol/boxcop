#if os(macOS)
import SwiftUI
import BoxCopCore

@MainActor struct NetworkSummaryView: View {
    let summary: NetworkActivitySummary?
    let error: String?
    @State private var range = "Today"
    @State private var grouping = "Apps"
    @State private var search = ""

    private var periodRows: [NetworkSummaryRow] {
        let today = Calendar.current.startOfDay(for: Date())
        let start = range == "Today" ? today : Calendar.current.date(byAdding: .day, value: -6, to: today)!
        return (summary?.rows ?? []).filter { $0.day >= start }
    }
    private var filtered: [NetworkSummaryRow] {
        periodRows.filter {
            (grouping != "Blocked" || $0.blocked > 0) &&
            (search.isEmpty || [$0.app, $0.process, $0.destination].joined(separator: " ").localizedCaseInsensitiveContains(search))
        }
    }
    private var groups: [Group] {
        Dictionary(grouping: filtered, by: { grouping == "Domains" ? destinationLabel($0) : $0.app })
            .map { Group(key: $0.key, rows: $0.value) }
            .sorted { $0.attempts == $1.attempts ? $0.key < $1.key : $0.attempts > $1.attempts }
    }
    private func destinationLabel(_ row: NetworkSummaryRow) -> String {
        row.isDomain ? row.destination : "\(row.destination) (hostname unavailable)"
    }
    private struct Group: Identifiable {
        let key: String
        let rows: [NetworkSummaryRow]
        var id: String { key }
        var attempts: Int { rows.reduce(0) { $0 + $1.attempts } }
        var blocked: Int { rows.reduce(0) { $0 + $1.blocked } }
        var lastSeen: Date { rows.map(\.lastSeen).max() ?? .distantPast }
    }
    private func children(of group: Group) -> [Group] {
        let children = Dictionary(grouping: group.rows, by: { grouping == "Domains" ? $0.app : destinationLabel($0) })
        return children.map { Group(key: $0.key, rows: $0.value) }
            .sorted { $0.attempts == $1.attempts ? $0.key < $1.key : $0.attempts > $1.attempts }
    }
    private func subtitle(_ group: Group) -> String {
        if grouping == "Domains" { return "\(Set(group.rows.map(\.app)).count) apps" }
        let domains = Set(group.rows.filter(\.isDomain).map(\.destination)).count
        let ips = Set(group.rows.filter { !$0.isDomain }.map(\.destination)).count
        return "\(domains) domains · \(ips) destinations without hostnames"
    }
    private func groupView(_ group: Group) -> some View {
        DisclosureGroup {
            ForEach(children(of: group)) { child in childView(child) }
        } label: {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(grouping == "Domains" ? group.key : URL(fileURLWithPath: group.key).lastPathComponent).fontWeight(.medium)
                    Text(subtitle(group)).foregroundStyle(Palette.quiet)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 3) {
                    Text("\(group.attempts) attempts · \(group.blocked) blocked")
                    Text(group.lastSeen, style: .relative).foregroundStyle(Palette.quiet)
                }
            }.help(group.key)
        }.padding(.vertical, 4)
    }
    private func childView(_ child: Group) -> some View {
        let first = (child.rows.map(\.firstSeen).min() ?? child.lastSeen).formatted(date: .abbreviated, time: .shortened)
        let last = child.lastSeen.formatted(date: .abbreviated, time: .shortened)
        let processes = Set(child.rows.map(\.processName)).sorted().joined(separator: ", ")
        return VStack(alignment: .leading, spacing: 4) {
            Text(child.key).textSelection(.enabled)
            Text("\(child.attempts) attempts · \(child.blocked) blocked · First: \(first) · Last: \(last)").foregroundStyle(Palette.quiet)
            Text("Processes: \(processes)").foregroundStyle(Palette.quiet)
            ForEach(Array(Set(child.rows.compactMap(\.blockedReason))).sorted(), id: \.self) { reason in
                Text(reason).foregroundStyle(Palette.amber)
            }
        }.padding(.vertical, 5).frame(maxWidth: .infinity, alignment: .leading)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Apps and hosts").font(.system(size: 12.5, weight: .semibold))
                Spacer()
                Picker("Time range", selection: $range) {
                    Text("Today").tag("Today")
                    Text("Last 7 days").tag("Last 7 days")
                }.frame(width: 220)
            }
            if let summary {
                let blocked = periodRows.reduce(0) { $0 + $1.blocked }
                Text("\(Set(periodRows.map(\.app)).count) apps · \(Set(periodRows.filter(\.isDomain).map(\.destination)).count) domains · \(periodRows.reduce(0) { $0 + $1.attempts }) attempts")
                Label(blocked == 0 ? "No blocked attempts in this period" : "\(blocked) attempts blocked: hosts on the threat list",
                      systemImage: blocked == 0 ? "shield" : "shield.lefthalf.filled")
                    .foregroundStyle(blocked == 0 ? Palette.quiet : Palette.red)
                Text("Statistics collected since \(summary.since.formatted(date: .abbreviated, time: .shortened)). Last 7 days includes today. Counts describe attempts, not transferred data.")
                    .foregroundStyle(Palette.quiet)
                if summary.omitted > 0 {
                    Text("Summary capacity reached: \(summary.omitted) attempts omitted since statistics began. Totals are incomplete.").foregroundStyle(Palette.amber)
                }
                Picker("Group by", selection: $grouping) {
                    ForEach(["Apps", "Domains", "Blocked"], id: \.self) { Text($0).tag($0) }
                }.pickerStyle(.segmented)
                TextField("Search apps, processes, domains or IP addresses", text: $search)
                if groups.isEmpty {
                    Text(search.isEmpty ? (grouping == "Blocked" ? "No blocked attempts in this period." : "No activity recorded in this period yet.") : "No matching activity in this period.")
                        .foregroundStyle(Palette.quiet)
                }
                ForEach(groups) { group in
                    groupView(group)
                }
            } else {
                Text("The summary is not available yet.")
                    .foregroundStyle(Palette.quiet)
            }
            if let error { Text(error).foregroundStyle(Palette.amber) }
        }.font(.system(size: 12))
    }
}
#endif
