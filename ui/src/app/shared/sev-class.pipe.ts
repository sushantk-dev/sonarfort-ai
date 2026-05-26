import { Pipe, PipeTransform } from '@angular/core';
@Pipe({ name: 'sevClass', standalone: true })
export class SevClassPipe implements PipeTransform {
  transform(value: string): string {
    return value.toLowerCase();
  }
}
