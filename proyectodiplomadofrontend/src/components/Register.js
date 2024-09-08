// components/Register.js
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Register.css';

function Register() {
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [passwrd, setPasswrd] = useState('');

    const handleLoginClick = () => {
        navigate('/login');
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, passwrd }),
            });

            if (response.ok) {
                alert('Registro exitoso');
                navigate('/login');
            } else {
                const errorText = await response.text();
                alert(`Error: ${errorText}`);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Ocurrió un error');
        }
    };

    return (
        <div className="container">
            <div className="register-container">
                <div className="form-container">
                    <h2>Register</h2>
                    <form onSubmit={handleSubmit}>
                        <label htmlFor="email">Correo electrónico:</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <label htmlFor="passwrd">Contraseña:</label>
                        <input
                            type="password"
                            id="passwrd"
                            name="passwrd"
                            value={passwrd}
                            onChange={(e) => setPasswrd(e.target.value)}
                            required
                        />
                        <button className="button-85" role="button" type="submit">
                            <span className="text">Register</span>
                        </button>
                    </form>
                    <p className="login-link" onClick={handleLoginClick}>
                        Ya tengo cuenta
                    </p>
                </div>
            </div>
        </div>
    );
}

export default Register;
