import {Component} from '@angular/core';
import {CdkDragDrop, CdkDropList, moveItemInArray, transferArrayItem} from '@angular/cdk/drag-drop'

@Component({selector: 'app-root', templateUrl: './app.component.html', styleUrls: ['./app.component.css']})
export class AppComponent {
    title = 'NO-kanban app';
    newItems = ['Item 0', 'Item 1', 'Item 2', 'Item 3'];
    activeItems = ['Item 4'];
    doneItems = ['Item 5', 'Item 6', 'Item 7'];
    dropped(event : CdkDragDrop < string[] >) {
      console.log(event);
        if (event.previousContainer === event.container) {
            moveItemInArray(event.container.data, event.previousIndex, event.currentIndex);
        } else {
            transferArrayItem(event.previousContainer.data, event.container.data, event.previousIndex, event.currentIndex);
        }
    }
}
