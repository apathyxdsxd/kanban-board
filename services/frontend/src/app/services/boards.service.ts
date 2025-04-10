import { Observable,of } from 'rxjs';
import { Injectable } from '@angular/core';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class BoardsService {

  constructor(
    private _api : ApiService,
    private _auth: AuthService,
  ) {}

  // we need to notify the progressbar-component about any changes regarding the cards
  private changeSubject = new Subject<any>();
  
  emitChangeEvent(event: any) {
    this.changeSubject.next(event);
  }

  getChangeEvent() {
    return this.changeSubject.asObservable();
  }  

  getBoards():Observable<Object>{
    return(this._api.getTypeRequest('getBoards'));
  }

  getCards(boardId:number):Observable<Object>{
    return(this._api.getTypeRequest(`getCards?boardId=${boardId}`));
  }

  createEmptyBoard():Observable<Object>{
    let Title:String=encodeURI('new empty board');
    return(this._api.postTypeRequest(`createEmptyBoard?Title=${Title}`,{}));
  }
  createEmptyCard(boardId:number,Column:String):Observable<Object>{    
    return(this._api.postTypeRequest(`createEmptyCard?boardId=${boardId}&column=${Column}`,{}));
  }  

  renameBoard(board:any):Observable<Object>{    
    return(this._api.postTypeRequest('renameBoard',
           {"title":board.title,
            "id":board.id,
            "owner_id":board.owner_id}));
/*     {
      "owner_id": 2,
      "title": "new emwas",
      "id": 2,
      "cards": []
    } */    
  }

  deleteBoard(board:any):Observable<Object>{    
    return(this._api.postTypeRequest('deleteBoard',
           {"title":board.title,
            "id":board.id,
            "owner_id":board.owner_id}));
  }  

  deleteCard(boardId:number,cardId:number):Observable<Object>{    
    return(this._api.postTypeRequest(`deleteCard?boardId=${boardId}&cardId=${cardId}`,{}));
  }    

  renameCard(boardId:number,cardId:number,newText:String):Observable<Object>{    
    return(this._api.postTypeRequest(`renameCard?boardId=${boardId}&cardId=${cardId}&newText=${newText}`,{}));
  }     

  reorderItems(board_id:number, items:Array<Array<number>>):Observable<Object>{
    return(this._api.postTypeRequest('reorderItems',
      {
        "board_id":board_id,
        "items":items
      }
    ));
  }


  moveItem(board_id:number, card_id:number, card_status:string):Observable<Object>{
    return(this._api.postTypeRequest(`moveItem?board_id=${board_id}&card_id=${card_id}&card_status=${card_status}`,{}));
  }
}