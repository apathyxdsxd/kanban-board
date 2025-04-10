import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

const AUTH_API = 'http://localhost:5000/';

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json',
                             'access-control-allow-origin': "http://localhost:5000/"})  
};

@Injectable({
  providedIn: 'root'
})
export class RegisterService {
  constructor(private http: HttpClient) { }

  register(email: string, password: string): Observable<any> {
    return this.http.post(AUTH_API + 'register', {
      email,
      password
    }, httpOptions);
  }
}
