// src/components/UserList.js
import React from 'react';
import UserItem from './UserItem';
import './UserList.css';

function UserList({ users, onSelectUser }) {
    return (
        <div className="user-list">
            {users.map((user, index) => (
                <UserItem key={index} userName={user} />
            ))}
        </div>
    );
}

export default UserList;
