import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
//import { ConsoleReporter } from 'jasmine';
import { AuthService } from 'src/app/services/auth.service';
import {ApiService} from '../../services/api.service'

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  //form!: FormGroup
  form: any = {
    email: null,
    password: null
  };
  isSuccessful = false;
  isSignUpFailed = false;
  errorMessage = '';  

  constructor(
    private _api : ApiService,
    private _auth: AuthService,
    private router: Router,
    public fb: FormBuilder
  ) { }

  ngOnInit(): void {
    this.form = this.fb.group({
      email: ['', Validators.required],
      password:['', Validators.required]
    });
   
  }

  login(){
    //let b = this.form.value
    //console.log('this.form.value:');
    //console.log(b)

    const { email, password } = this.form;
    let b = this.form;
    //console.log({email,password});

    this._api.postTypeRequest('login', {email,password}).subscribe((res: any) => {
      console.log(res)
      if(res.access_token){
        this._auth.setDataInLocalStorage('token', res.access_token)
        this.router.navigate(['profile'])
      }
    }, err => {
      console.log(err)
      //if(err.)
      this.errorMessage = err.error.message;
      this.isSignUpFailed = true;      
      //this.form.controls['email'].setErrors({invalid: true});
    });
  }

  navigateToSignUp(){
    this.router.navigate(['register'])
  }  

}