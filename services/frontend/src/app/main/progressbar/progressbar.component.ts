import { Component, Input,OnDestroy,OnInit, SimpleChanges } from '@angular/core';
import { BoardsService } from '../../services/boards.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-progressbar',
  templateUrl: './progressbar.component.html',
  styleUrls: ['./progressbar.component.css']
})
export class ProgressbarComponent implements OnInit, OnDestroy {
  
  @Input() boardId=-1;
  @Input() cards=[] as any[];
  new_cards: number = 0;
  wip_cards: number = 0;
  done_cards: number = 0;
  progress:number = 0;
  private changeEventSubscription: Subscription;

  constructor(private _boardsService:BoardsService) { 
    this.changeEventSubscription = this._boardsService.getChangeEvent().subscribe((eventData) => {
      console.log('\nCHANGE EVENT:\n');
      console.log({eventData});
      this.new_cards = eventData.data.newItems.length;
      this.wip_cards = eventData.data.activeItems.length;
      this.done_cards = eventData.data.doneItems.length;
      this.progress = this.done_cards/(this.new_cards + this.wip_cards + this.done_cards)*100
    });
  }

  /* 1st approach. Doesn't work because @Input-property 'cards' doesn't really change when
     cards are moved across columns. 
     Worarkound: emit event from boards.component.ts and subscribe in this component
  */
 /*
  ngOnChanges(changes: SimpleChanges) {    
    if (changes['cards'] && this.cards) {
      //this.updateProgress();
    }
  }
  */

  ngOnInit(): void {
    this.new_cards = this.cards.filter(item => item.status === 'new').length;
    this.wip_cards = this.cards.filter(item => item.status === 'wip').length;
    this.done_cards = this.cards.filter(item => item.status === 'done').length;    
    this.progress = this.done_cards/(this.new_cards + this.wip_cards + this.done_cards)*100
  }

  ngOnDestroy(): void {
      this.changeEventSubscription.unsubscribe();
  }

}
