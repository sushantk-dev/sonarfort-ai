import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name: 'shortComp', standalone: true })
export class ShortCompPipe implements PipeTransform {
  transform(value: string): string {
    return value.split(':').pop() ?? value;
  }
}
