// src/app/shared/active-step.pipe.ts
import { Pipe, PipeTransform } from '@angular/core';
import { PipelineStep } from '../core/api.service';

@Pipe({ name: 'activeStep', standalone: true })
export class ActiveStepPipe implements PipeTransform {
  transform(steps: PipelineStep[]): string {
    return steps?.find(s => s.status === 'running')?.label ?? '';
  }
}