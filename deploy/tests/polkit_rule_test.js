"use strict";

const fs = require("fs");
const vm = require("vm");

let rule;
const sandbox = {
    polkit: {
        Result: { YES: "YES", NOT_HANDLED: "NOT_HANDLED" },
        addRule: candidate => { rule = candidate; },
    },
};
const source = fs.readFileSync(process.argv[2], "utf8");
vm.runInNewContext(source, sandbox, { filename: process.argv[2] });
if (typeof rule !== "function") throw new Error("polkit rule was not registered");

function action(id, unit, verb) {
    return { id, lookup: key => ({ unit, verb })[key] };
}
function expect(label, got, want) {
    if (got !== want) throw new Error(`${label}: got ${got}, want ${want}`);
}

const yes = sandbox.polkit.Result.YES;
const no = sandbox.polkit.Result.NOT_HANDLED;
const agent = { user: "pgw-agent" };
expect("valid start", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@15001.service", "start"), agent), yes);
expect("valid stop", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@15999.service", "stop"), agent), yes);
expect("different user", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@15001.service", "start"), { user: "pgw-api" }), no);
expect("wrong action", rule(action("org.freedesktop.systemd1.manage-unit-files", "pgw-fwd@15001.service", "start"), agent), no);
expect("status verb", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@15001.service", "status"), agent), no);
expect("other unit", rule(action("org.freedesktop.systemd1.manage-units", "pgw-api.service", "restart"), agent), no);
expect("template unit", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@.service", "restart"), agent), no);
expect("leading zero", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@015001.service", "restart"), agent), no);
expect("below range", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@15000.service", "restart"), agent), no);
expect("above range", rule(action("org.freedesktop.systemd1.manage-units", "pgw-fwd@16000.service", "restart"), agent), no);

process.stdout.write("polkit rule tests: PASS\n");
