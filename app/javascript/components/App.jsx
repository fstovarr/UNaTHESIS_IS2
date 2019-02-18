import React from "react"
import PropTypes from "prop-types"

import { BrowserRouter, Switch, Route, Redirect } from 'react-router-dom'

import auth from '../services/auth'
import LoginForm from './LoginForm'
import LoadProjectForm from './LoadProjectForm'
import ViewProject from './ViewProject'
import ProtectedRoute from './ProtectedRoute'

/** 
 * All the application's paths must be declarated this.
 * 
 * @type {Array}
 * @property {string} path Route to be driven.
 * @property {boolean} restricted True or not define for indicate that the path will 
 *                                be restricted (only authenticated users can access), False.
 * @property {Map} componentParams Parameters of the component
 *
 * More properties (https://reacttraining.com/react-router/web/api/Route)
 */
 const routes = [
 { path: "/project/load", exact: null, component: LoadProjectForm},
 { path: "/project/view", exact: null, component: ViewProject },
 { path: "/404.html", exact:null, restricted: false }
 ];

 class App extends React.Component {
 	constructor() {
 		super();

 		this.routes = routes;
 		this.routes.push({ 
 			path: "/login", 
 			exact: null, 
 			componentProps: {
 				updateAuth: this.updateAuth.bind(this)
 			},
 			component: LoginForm,
 			restricted: false
 		});

 		this.state = { isAuthenticated: auth.isAuthenticated() }
 	}

 	updateAuth() {
 		this.setState({
 			isAuthenticated: auth.isAuthenticated()
 		});
 	}

 	logout(e) {
 		e.preventDefault();
 		auth.logout();
 		this.updateAuth();
 	}

 	render () {
 		return (
 			<div>
 			<BrowserRouter>
 			<Switch>
 			{
 				this.routes.map(function(route, index) {
 					return <ProtectedRoute { ...route } key={ index } />;
 				}, this)
 			}
 			<Route exact render={() => {window.location.href="404.html"}} />
 			</Switch>
 			</BrowserRouter>
 			</div>
 			);	
 	}
 }

 export default App
