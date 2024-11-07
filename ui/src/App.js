import React, { useEffect, useState } from 'react';
import axios from 'axios';

function App() {
    const [checks, setChecks] = useState([]);
    const [compliances, setCompliances] = useState([]);

    useEffect(() => {
        axios.get('http://localhost:8000/checks')
            .then(response => {
                setChecks(response.data);
            })
            .catch(error => {
                console.error('Error fetching checks: ', error);
            });

        axios.get('http://localhost:8000/compliances')
            .then(response => {
                setCompliances(response.data);
            })
            .catch(error => {
                console.error('Error fetching compliances: ', error);
            });
    }, []);

    return (
        <div className="App">
            <h1>Checks</h1>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Description</th>
                        <th>Provider</th>
                    </tr>
                </thead>
                <tbody>
                    {checks.map((check) => (
                        <tr key={check.id}>
                            <td>{check.id}</td>
                            <td>{check.title}</td>
                            <td>{check.description}</td>
                            <td>{check.provider}</td>
                        </tr>
                    ))}
                </tbody>
            </table>

            <h1>Compliances</h1>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Framework</th>
                        <th>Description</th>
                        <th>Provider</th>
                    </tr>
                </thead>
                <tbody>
                    {compliances.map((compliance) => (
                        <tr key={compliance.id}>
                            <td>{compliance.id}</td>
                            <td>{compliance.framework}</td>
                            <td>{compliance.description}</td>
                            <td>{compliance.provider}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default App;
