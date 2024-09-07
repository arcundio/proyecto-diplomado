import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

function LoginSuccess() {
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
        // Obtener los parámetros de la URL
        const params = new URLSearchParams(location.search);
        const token = params.get('token');
        const userID = params.get('userID');

        if (token && userID) {
            // Guardar token y userID en localStorage
            localStorage.setItem('jwt', token);
            localStorage.setItem('userID', userID);

            // Redirigir a la página de datos
            navigate('/data');
        } else {
            // Redirigir a una página de error si faltan parámetros
            navigate('/error');
        }
    }, [location, navigate]);

    return <div>Cargando...</div>;
}

export default LoginSuccess;
