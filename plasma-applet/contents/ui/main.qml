import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts

import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.core as PlasmaCore
import org.kde.plasma.plasmoid
import org.kde.plasma.plasma5support as Plasma5Support

PlasmoidItem {
    id: root

    readonly property string statusCommand: "/usr/local/bin/agent-root-runner status"
    property string daemonState: "UNKNOWN"
    property bool armed: false
    property bool forever: false
    property string remaining: ""
    property string quotaRemaining: ""
    property string commandsExecuted: ""
    property string message: "Connecting to Agent Root Runner…"
    property bool actionRunning: false
    property bool statusRunning: false
    property bool foreverSelected: false
    property bool quotaEnabled: true

    Plasmoid.icon: armed ? "security-high" : "security-low"
    Plasmoid.status: message.startsWith("Error:")
        ? PlasmaCore.Types.NeedsAttentionStatus
        : (armed ? PlasmaCore.Types.ActiveStatus : PlasmaCore.Types.PassiveStatus)
    toolTipMainText: "Agent Root Runner: " + daemonState
    toolTipSubText: armed
        ? (forever ? "ARM has no time limit" : "Remaining: " + remaining)
        : "Privileged execution is disabled"

    Plasma5Support.DataSource {
        id: processSource
        engine: "executable"
        connectedSources: []

        onNewData: function(sourceName, data) {
            disconnectSource(sourceName)
            const output = String(data["stdout"] || "")
            const error = String(data["stderr"] || "").trim()

            if (sourceName === root.statusCommand) {
                root.statusRunning = false
                if (output.length === 0) {
                    root.message = "Error: " + (error || "Could not read daemon status")
                    root.daemonState = "UNAVAILABLE"
                    root.armed = false
                    root.forever = false
                    return
                }
                root.daemonState = root.readField(output, "State") || "UNKNOWN"
                root.armed = root.daemonState === "ARMED"
                root.forever = root.armed && root.readField(output, "Forever") === "True"
                root.remaining = root.readField(output, "Remaining") || ""
                root.quotaRemaining = root.readField(output, "Quota remaining") || "Unlimited"
                root.commandsExecuted = root.readField(output, "Commands executed") || "0"
                root.message = root.armed
                    ? (root.forever ? "ARMED without a time limit" : "ARMED — " + root.remaining + " seconds remaining")
                    : "DISARMED — privileged execution is disabled"
                return
            }

            root.actionRunning = false
            root.message = error.length > 0
                ? "Error: " + error
                : (output.trim() || "Command completed")
            root.refreshStatus()
        }
    }

    function readField(output, field) {
        const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
        const match = output.match(new RegExp("^" + escaped + ":\\s*(.*)$", "m"))
        return match ? match[1].trim() : ""
    }

    function launch(command) {
        processSource.connectSource(command)
    }

    function refreshStatus() {
        if (statusRunning)
            return
        statusRunning = true
        launch(statusCommand)
    }

    function startArm(withoutTimeLimit) {
        if (actionRunning)
            return
        let command = "pkexec /usr/local/bin/agent-root-runner arm"
        if (withoutTimeLimit) {
            command += " --forever"
        } else {
            command += " --duration " + durationInput.value
        }
        if (quotaEnabled)
            command += " --quota " + quotaInput.value
        actionRunning = true
        message = withoutTimeLimit ? "Waiting for confirmation to ARM without a time limit…" : "Waiting for authorization to ARM…"
        launch(command)
    }

    function requestArm() {
        if (foreverSelected)
            foreverConfirmation.open()
        else
            startArm(false)
    }

    function disarm() {
        if (actionRunning)
            return
        actionRunning = true
        message = "Disarming…"
        launch("/usr/local/bin/agent-root-runner disarm")
    }

    Component.onCompleted: refreshStatus()

    Timer {
        interval: 3000
        repeat: true
        running: true
        onTriggered: root.refreshStatus()
    }

    compactRepresentation: Item {
        implicitWidth: Kirigami.Units.iconSizes.small
        implicitHeight: Kirigami.Units.iconSizes.small

        Kirigami.Icon {
            anchors.fill: parent
            source: root.armed ? "security-high" : "security-low"
        }

        MouseArea {
            anchors.fill: parent
            onClicked: Plasmoid.expanded = !Plasmoid.expanded
        }
    }

    fullRepresentation: ColumnLayout {
        Layout.minimumWidth: Kirigami.Units.gridUnit * 20
        Layout.minimumHeight: Kirigami.Units.gridUnit * 17
        spacing: Kirigami.Units.smallSpacing

        QQC2.Label {
            Layout.fillWidth: true
            text: root.armed
                ? (root.forever ? "ARMED — no time limit" : "ARMED — " + root.remaining + " seconds remaining")
                : "DISARMED"
            font.bold: true
            wrapMode: Text.Wrap
        }

        QQC2.Label {
            Layout.fillWidth: true
            text: root.message
            wrapMode: Text.Wrap
        }

        QQC2.Label {
            Layout.fillWidth: true
            text: "Quota remaining: " + root.quotaRemaining + "   Commands executed: " + root.commandsExecuted
            visible: root.armed
            wrapMode: Text.Wrap
        }

        Kirigami.Separator {
            Layout.fillWidth: true
        }

        QQC2.CheckBox {
            id: foreverCheck
            Layout.fillWidth: true
            text: "No time limit"
            checked: root.foreverSelected
            onToggled: root.foreverSelected = checked
        }

        QQC2.Label {
            Layout.fillWidth: true
            visible: root.foreverSelected
            text: "Warning: ARM stays active until manually disarmed, its quota runs out, or the daemon restarts."
            wrapMode: Text.Wrap
        }

        RowLayout {
            Layout.fillWidth: true
            visible: !root.foreverSelected
            QQC2.Label { text: "Duration (seconds)" }
            QQC2.SpinBox {
                id: durationInput
                from: 1
                to: 86400
                value: 300
                editable: true
                Layout.fillWidth: true
            }
        }

        RowLayout {
            Layout.fillWidth: true
            QQC2.CheckBox {
                id: quotaCheck
                text: "Limit commands"
                checked: root.quotaEnabled
                onToggled: root.quotaEnabled = checked
            }
            QQC2.SpinBox {
                id: quotaInput
                from: 1
                to: 1000000
                value: 10
                editable: true
                enabled: root.quotaEnabled
                Layout.fillWidth: true
            }
        }

        RowLayout {
            Layout.fillWidth: true
            PlasmaComponents3.Button {
                text: "ARM"
                icon.name: "security-high"
                enabled: !root.actionRunning
                onClicked: root.requestArm()
            }
            PlasmaComponents3.Button {
                text: "Disarm"
                icon.name: "security-low"
                enabled: !root.actionRunning
                onClicked: root.disarm()
            }
            PlasmaComponents3.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                enabled: !root.statusRunning
                onClicked: root.refreshStatus()
            }
        }
    }

    QQC2.Dialog {
        id: foreverConfirmation
        title: "ARM without a time limit?"
        standardButtons: QQC2.Dialog.Ok | QQC2.Dialog.Cancel
        modal: true
        onAccepted: root.startArm(true)

        contentItem: QQC2.Label {
            text: "Privileged execution will remain enabled until you disarm it, the command quota is exhausted, or the daemon restarts. Continue to the system authorization prompt?"
            wrapMode: Text.Wrap
            width: Kirigami.Units.gridUnit * 20
        }
    }
}
