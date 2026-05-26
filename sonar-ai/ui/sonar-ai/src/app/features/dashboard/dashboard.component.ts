// src/app/features/dashboard/dashboard.component.ts
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent {
  pipelineSteps = [
    { name: 'Ingest',      desc: 'Parse + sort'     },
    { name: 'Load Repo',   desc: 'Clone + AST'      },
    { name: 'RAG Fetch',   desc: 'Vector store'     },
    { name: 'Rule Fetch',  desc: 'Sonar rule API'   },
    { name: 'Planner',     desc: 'Chain-of-thought'  },
    { name: 'Generator',   desc: 'Unified diff'     },
    { name: 'Critic',      desc: 'Review patch'     },
    { name: 'Validate',    desc: 'git + mvn'        },
    { name: 'Deliver',     desc: 'PR / Escalate'    },
  ];
}