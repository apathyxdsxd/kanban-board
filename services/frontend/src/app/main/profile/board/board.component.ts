import { Component, Input, OnInit, SimpleChanges } from '@angular/core';
import {CdkDragDrop, CdkDropList, moveItemInArray, transferArrayItem} from '@angular/cdk/drag-drop'
import { BoardsService } from 'src/app/services/boards.service';
import { ConnectableObservable } from 'rxjs';
import { NullVisitor } from '@angular/compiler/src/render3/r3_ast';

@Component({
  selector: 'app-board',
  templateUrl: './board.component.html',
  /* template:'<mat-tab label="First">Content 1</mat-tab>', */
  styleUrls: ['./board.component.css']
})


export class BoardComponent implements OnInit {
/*   items={'newItems':['Item 0', 'Item 1', 'Item 2', 'Item 3'],
  'activeItems':['Item4','Item5'],
  'doneItems':['Item6','Item7']}; */

  items={'newItems':[] as any,
         'activeItems':[] as any,
         'doneItems':[] as any};  

  @Input() boardId=-1;
  @Input() cards=[] as any[];

  constructor(private _boardsService:BoardsService) { }

  ngOnInit(): void {

    this.loadItems();    

    //this.cards.sort((a:any,b:any)=>a.order_id-b.order_id); 
  }
  
  // we need to tell the progress-bar, when data regarding the cards changes
  emitGlobalChangeEvent() {
    this._boardsService.emitChangeEvent({ data: this.items });
  }

  loadItems():void {

    this.items={'newItems':[] as any,
    'activeItems':[] as any,
    'doneItems':[] as any};  

    this._boardsService.getCards(this.boardId).subscribe(
      (resp:any) => {
        console.log("GET CARDS RESPONSE:");        
        console.log(resp);
        this.cards=resp;
        this.cards.forEach( (k)=>{
          switch(k['status']){
            case "new":
              this.items['newItems'].push(k);
              break;
            case "wip":
              this.items['activeItems'].push(k);
              break;
            case "done":
              this.items['doneItems'].push(k);
              break;          
          }
          this.emitGlobalChangeEvent();
        });                
      }, (err: any) => {
        console.log(err);
      }
    );        

  }

  /* dropped(event : CdkDragDrop < string[] >) { */
  dropped(event : CdkDragDrop < any[] >) {
      console.log({event});
      // same-column movement
      if (event.previousContainer === event.container) {
          moveItemInArray(event.container.data, event.previousIndex, event.currentIndex);
          // Insert API-Call here to change order
          event.container.data.forEach((x,index)=>x.order_id=index);
          // prepare api-object. Parenthesis around new objs are needed!
          
          const params=event.container.data.map(x=>[x.id,x.order_id]);
          //console.log(params);

          // container id ist eins von ["newColumn","activeColumn","doneColumn"]
          this._boardsService.reorderItems(this.boardId, params).subscribe(
            {error:console.warn}
          )                     
        
      } 
      // cross-column movement
      else {
          // update status
          let updateStatus='';
          switch(event.container.id){
            case "newColumn":
              updateStatus="new";
              break;
            case "activeColumn":
              updateStatus="wip";
              break;
            case "doneColumn":
              updateStatus="done";
              break;
          }
          // status of card is set before transferArrayItem
          event.previousContainer.data[event.previousIndex].status=updateStatus;
          transferArrayItem(event.previousContainer.data, event.container.data, event.previousIndex, event.currentIndex); 
          
          // ReorderItems Code goes here
          event.container.data.forEach((x,index)=>x.order_id=index);
          event.previousContainer.data.forEach((x,index)=>x.order_id=index);

          const params1=event.container.data.map(x=>[x.id,x.order_id]);
          const params2=event.previousContainer.data.map(x=>[x.id,x.order_id]);
          const params_all=params1.concat(params2);

          /*
          console.log('Move Across');
          console.log(event);    
          console.log(event.item.data);      
          console.log({params1});
          console.log({params2});
          */

          this._boardsService.reorderItems(this.boardId, params_all).subscribe(
            {error:console.warn}
          )  

          // MoveAcrossCard Code goes here
          //console.log(event.item.data.id, event.item.data.status);
          this._boardsService.moveItem(this.boardId,event.item.data.id, event.item.data.status).subscribe(
            {error:console.error}
          )

          this.emitGlobalChangeEvent();

          
      }
  }
  crossOffItem(event:[string,number]){
    console.log(event);
    // https://stackoverflow.com/questions/57086672/element-implicitly-has-an-any-type-because-expression-of-type-string-cant-b    
    let cardId = event[1]; // actual Id in db
    let cardIndex = this.items[event[0] as keyof typeof this.items].findIndex((k:any) => k.id === cardId); // just the array-index

    this.items[event[0] as keyof typeof this.items].splice(cardIndex,1);

    //console.log('deleted id: '+cardId + ' at index ' + cardIndex);

    // DeleteCard code goes here
    this._boardsService.deleteCard(this.boardId,cardId).subscribe(
      (resp:any)=>{
        console.log(resp);
      },
      (err:any)=>{
        console.log(err);
      }
    )
    
    this.emitGlobalChangeEvent();
  }

  renameCard(event:[string,number]){
    const cardId = event[1];
    const newText = event[0];
  

    // don't forget to rename the card also on the frontend-side
    // ohterwise the text of a card moving across columns will be reset 
    // to the default "new empty card"
    let mycard:any = this.cards.find((obj:any) => obj.id === cardId);
    if (mycard) {
      mycard.text = newText;
      console.log(mycard);
      console.log(this.cards);
    }
    
  
    
    this._boardsService.renameCard(this.boardId,cardId, newText).subscribe(
      (resp:any)=>{
        console.log(resp);
      },
      (err:any)=>{
        console.log(err);
      }
    )       
  }

  addCard(Column:String){
    this._boardsService.createEmptyCard(this.boardId,Column).subscribe(
      (card:any)=>{
        // we need to add the card to the fronted-memory as well
        // this is part of fixing the bug, where the text of a card is lost
        // upon moving it across columns
        this.cards.push(card);
        switch(Column){
          case "newColumn":
            this.items.newItems.push(card);            
            break;
          case "activeColumn":
            this.items.activeItems.push(card);
            break;
          case "doneColumn":
            this.items.doneItems.push(card);
            break;
        } 
        this.emitGlobalChangeEvent()                
      },
      (err:any)=>{
        console.log(err);
      }
    )    
    
  }     
  
}
