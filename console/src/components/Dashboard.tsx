import {
  Braces,
  Building2,
  FileCode2,
  Gauge,
  GitBranch,
  KeyRound,
  Network,
  SearchCode,
  Settings,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { TASK_ROUTES } from "../lib/routes";
import { BackendStatus } from "./BackendStatus";
import { LoginPanel } from "./LoginPanel";

const icons = [FileCode2, Network, Building2, UserRound, GitBranch, Braces, ShieldCheck, KeyRound, SearchCode, Settings];

export default function Dashboard() {
  return (
    <div className="dashboard">
      <section className="page-heading">
        <div>
          <p className="eyebrow">Console shell</p>
          <h1>Atom API Builder</h1>
        </div>
        <BackendStatus />
      </section>

      <div className="dashboard-grid">
        <section className="panel span-2">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Quick actions</p>
              <h2>Workflows</h2>
            </div>
            <Gauge size={18} aria-hidden="true" />
          </div>
          <div className="task-grid">
            {TASK_ROUTES.map((route, index) => {
              const Icon = icons[index] ?? FileCode2;
              return (
                <a className="task-link" href={route.href} key={route.href}>
                  <Icon size={18} aria-hidden="true" />
                  <span>{route.label}</span>
                </a>
              );
            })}
          </div>
        </section>

        <LoginPanel />

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Recent</p>
              <h2>Custom APIs</h2>
            </div>
          </div>
          <p className="empty-state">No custom API activity in the shell phase.</p>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Recent</p>
              <h2>Endpoints</h2>
            </div>
          </div>
          <p className="empty-state">No endpoint activity in the shell phase.</p>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Recent</p>
              <h2>Executions</h2>
            </div>
          </div>
          <p className="empty-state">No execution activity in the shell phase.</p>
        </section>
      </div>
    </div>
  );
}
