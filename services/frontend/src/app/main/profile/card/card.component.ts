import { Component, OnInit, Input } from '@angular/core';
import { Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'app-card',
  templateUrl: './card.component.html',
  styleUrls: ['./card.component.css']
})
export class CardComponent implements OnInit {

  constructor() { 
  }
  @Input() cardContent='';
  @Input() cardId=-1;
  @Input() cardColumn='';
  @Output() deleteItem = new EventEmitter <[string,number]>();
  @Output() renameItem = new EventEmitter <[string,number]>();

  delItem() {
    this.deleteItem.emit([this.cardColumn,this.cardId]);    
  }

  onInputChange(event: Event) {
    // Cast the event target to an HTMLInputElement to access its value property
    const inputElement = event.target as HTMLInputElement;
    const inputValue = inputElement.value;
    
    // Perform any actions you want with the inputValue
    console.log('Input value changed:', inputValue);    
    console.log(`column:${this.cardColumn},id:${this.cardId}`);
    this.renameItem.emit([inputValue,this.cardId]);

    
    //console.log(`content:${this.cardContent}`); // that's the old text
    // we need to update the text manually (only one-way binding in html)
    this.cardContent=inputValue; 


  }

  ngOnInit(): void {
  }

}
