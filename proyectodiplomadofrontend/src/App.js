import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Login from './components/Login';
import DataWindow from './components/DataWindow';
import ProtectedRoute from './components/ProtectedRoute';
import Register from './components/Register';
import FileDetail from "./components/FileDetail";
import LoginSuccess from "./components/LoginSucess";

function App() {
    return (
        <div className="app-container">
            <Router>
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/login-success" element={<LoginSuccess />} />
                    <Route
                        path="/data"
                        element={<ProtectedRoute element={<DataWindow />} />}
                    />
                    <Route path="/data/file/:hash" element={<FileDetail/>} />
                    <Route path="*" element={<Login />} />
                </Routes>
            </Router>
        </div>
    );
}

export default App;
