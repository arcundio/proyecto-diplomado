// src/components/FileList.js
import React from 'react';
import FileItem from './FileItem';
import './FileList.css';

function FileList({ files }) {
    return (
        <div className="file-list">
            {files.map((file, index) => (
                <FileItem
                    key={index}
                    fileName={file.name}
                    fileSize={file.size}
                    iconType={file.type}
                />
            ))}
        </div>
    );
}

export default FileList;
