import { AppComponent } from './app.component';
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { LoginComponent } from './main/login/login.component';
import { ProfileComponent } from './main/profile/profile.component';
import { RegisterComponent } from './main/register/register.component';

import { AuthGuardService } from './services/auth-guard.service';


const routes: Routes = [
   
  { path: '', redirectTo: 'login', pathMatch: 'full' }, 
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'profile',    
    component: ProfileComponent,
    canActivate:[AuthGuardService] 
  },
  {
    path: 'register',
    component: RegisterComponent
  },  
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
