// App.js
import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import DataWindow from './components/DataWindow';

function App() {
    return (
        <div className="app-container">
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="*" element={<Login />} /> {/* Redirige a /login por defecto */}
                <Route path="/data" element={<DataWindow />} />
            </Routes>
        </div>
    );
}

export default App;
