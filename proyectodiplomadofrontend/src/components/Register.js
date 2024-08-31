// components/Register.js
import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Register.css';

function Register() {
    const navigate = useNavigate();

    const handleLoginClick = () => {
        navigate('/login');
    };

    return (
        <div className="container">
            <div className="register-container">
                <div className="form-container">
                    <h2>Register</h2>
                    <form>
                        <label htmlFor="email">Correo electrónico:</label>
                        <input type="email" id="email" name="email" />
                        <label htmlFor="password">Contraseña:</label>
                        <input type="password" id="password" name="password" />
                        <button className="button-85" role="button"><span className="text">Register</span></button>
                    </form>
                    <p className="login-link" onClick={handleLoginClick}>Ya tengo cuenta</p>
                </div>
            </div>
        </div>
    );
}

export default Register;
