import child_process from "node:child_process";

export function run(command: string): void {
  child_process.exec(command);
}
