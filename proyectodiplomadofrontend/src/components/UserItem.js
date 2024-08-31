// src/components/UserItem.js
import React from 'react';
import './UserItem.css';

function UserItem({ userName }) {
    return <div className="user-item">{userName}</div>;
}

export default UserItem;
