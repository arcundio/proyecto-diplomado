// index.js
import React from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter as Router } from 'react-router-dom';
import App from './App';
import './index.css'; // Ajusta el archivo CSS según sea necesario

ReactDOM.render(
    <Router>
        <App />
    </Router>,
    document.getElementById('root')
);
