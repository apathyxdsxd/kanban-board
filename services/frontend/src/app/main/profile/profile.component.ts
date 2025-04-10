import { BoardsService } from '../../services/boards.service';
import { Component, OnInit, ViewChild, AfterViewInit } from '@angular/core';
import { AuthService } from 'src/app/services/auth.service';
import {ApiService} from '../../services/api.service'
import { MatTabGroup } from '@angular/material/tabs';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {

  constructor(
    private _api : ApiService,
    private _auth: AuthService,
    private _boardsService:BoardsService
  ) { }

  ngOnInit(): void {
    this.test_jwt()
    this.getBoards();
  }
  @ViewChild(MatTabGroup)tabGroup!: MatTabGroup;

  // I need this workaround to auto-select the first tab because for some reason the last tab (just the 'add new board'-button) is selected,
  // even though I've defined [selectedIndex]="0" in the html-part.
  // This is likely realted to lazy-loading of the content of the other tabs, while the last tab doesn't have any content at all (except for the button)
  // The following post on SO says, that this is an angular-bug and suggested two-way binding the selectedIndex-property as a workaround,
  // which resulted in an error in my case: 
  // https://stackoverflow.com/a/47464160/1454931
  //
  ngAfterViewInit() {
    // Set focus to the first tab element
    setTimeout(() => {
      this.tabGroup.selectedIndex = 0; // Set focus on the first tab (index 0) after a short delay
    }, 0);
  }
  
  title = 'YAKB';  
  boards: Array<any>=[];
  owner_id:number=-1;
  
  test_jwt(){
    this._api.getTypeRequest('test-jwt').subscribe((res: any) => {
      console.log(res)
      this.owner_id=parseInt(res.user_id);

    }, (err:any) => {
      console.log(err)
    });
  }

  getBoards(){
    this._boardsService.getBoards().subscribe(
      (next:any) => {
        console.log("GETBOARD RESPONSE:");        
        console.log(next);
        next.forEach((k:any) => {          
          // Sortiere nach order_id der cards
          k['cards'].sort((a:any,b:any)=>a.order_id-b.order_id);          
          this.boards.push(k);          
        });
      }, (err: any) => {
        console.log(err);
      }, ()=>{
        console.log('OK');
      }      
    );
  
  }
  
  renameBoard(board:any){
    this._boardsService.renameBoard(board).subscribe(
      (resp:any)=>{
        console.log(resp);
      },
      (err:any)=>{
        console.log(err);
      }
    )       
  } 

  addBoard(){
    this._boardsService.createEmptyBoard().subscribe(
      (resp:any)=>{
        console.log(resp)
        resp.cards=[];
        this.boards.push(resp);
      },
      (err:any)=>{console.log(err)}      
    );        
  }

  deleteBoard(board:any){
    this._boardsService.deleteBoard(board).subscribe(
      (resp:any)=>{
        console.log("DEL RESP:");
        console.log(resp)
        //remove from array as well
        this.boards.splice(this.boards.findIndex(el => el.id === board.id),1);        
      },
      (err:any)=>{console.log(err)}      
    );        
  }  
}