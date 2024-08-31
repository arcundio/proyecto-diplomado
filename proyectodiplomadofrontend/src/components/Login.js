// components/Login.js
import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login() {
    const navigate = useNavigate();

    const handleRegisterClick = () => {
        navigate('/register');
    };

    return (
        <div className="container">
            <div className="login-container">
                <div className="form-container">
                    <h2>Login</h2>
                    <form>
                        <label htmlFor="username">Nombre de usuario:</label>
                        <input type="text" id="username" name="username" />
                        <label htmlFor="password">Contraseña:</label>
                        <input type="password" id="password" name="password" />
                        <button className="button-85" role="button"><span className="text">Login</span></button>
                    </form>
                    <p className="register-link" onClick={handleRegisterClick}>No tengo cuenta</p>
                </div>
            </div>
        </div>
    );
}

export default Login;
