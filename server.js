const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Fetch all users endpoint
app.get('/api/users', (req, res) => {
    const query = 'SELECT id, first_name, last_name, email, position, created_at, privileges FROM users';
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Server error during users fetch', error: err });
        }
        res.status(200).json(results);
    });
});
    // Update user privileges endpoint
    app.put('/api/users/:id/privileges', (req, res) => {
        const userId = req.params.id;
        const { privileges } = req.body;
    
        const query = 'UPDATE users SET privileges = ? WHERE id = ?';
        db.query(query, [JSON.stringify(privileges), userId], (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Server error during privileges update', error: err });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found' });
            }
            res.status(200).json({ message: 'Privileges updated successfully' });
        });
    });

// Update user endpoint
app.put('/api/users/:id', async (req, res) => {
    const userId = req.params.id;
    const { first_name, last_name, email, position, password } = req.body;

    try {
        // Check if the user is being changed to admin
        if (position === 'admin') {
            // Count the number of admins
            const adminCountQuery = 'SELECT COUNT(*) AS adminCount FROM users WHERE position = "admin"';
            const [adminCountResult] = await db.promise().query(adminCountQuery);
            const adminCount = adminCountResult[0].adminCount;

            // If there's already an admin and the user being updated is not the same user, return an error
            const userQuery = 'SELECT position FROM users WHERE id = ?';
            const [userResult] = await db.promise().query(userQuery, [userId]);
            const user = userResult[0];

            if (adminCount >= 1 && user.position !== 'admin') {
                return res.status(400).json({ message: 'Only one admin is allowed.' });
            }
        }

        // Hash the password if it's provided
        let hashedPassword = null;
        if (password) {
            hashedPassword = await bcrypt.hash(password, 10);
        }

        // Update the user
        const updateUserQuery = `
            UPDATE users 
            SET first_name = ?, last_name = ?, email = ?, position = ?, user_password = COALESCE(?, user_password)
            WHERE id = ?`;
        const values = [first_name, last_name, email, position, hashedPassword, userId];

        const [updateResult] = await db.promise().query(updateUserQuery, values);

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// Delete user endpoint
app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;

    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Database delete error:', err);
            return res.status(500).json({ message: 'Server error during user deletion', error: err });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({ message: 'User deleted successfully' });
    });
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, password, position } = req.body;
    console.log('Received registration request:', req.body);

    // Check if email already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Database query error during email check:', err);
            return res.status(500).json({ message: 'Server error during email check' });
        }
        if (results.length > 0) {
            console.log('User already exists:', email);
            return res.status(400).json({ message: 'User already exists' });
        }

        // Check the number of existing admin users
        if (position === 'admin') {
            db.query('SELECT COUNT(*) AS adminCount FROM users WHERE position = "admin"', async (err, countResults) => {
                if (err) {
                    console.error('Database query error during admin count check:', err);
                    return res.status(500).json({ message: 'Server error during admin count check' });
                }
                const adminCount = countResults[0].adminCount;
                if (adminCount >= 1) {
                    console.log('Admin registration limit reached');
                    return res.status(400).json({ message: 'Admin registration limit reached. Only 1 admin is allowed.' });
                }

                // Proceed with user registration
                try {
                    const hashedPassword = await bcrypt.hash(password, 10);
                    console.log('Password hashed successfully');
                    db.query(
                        'INSERT INTO users (first_name, last_name, email, user_password, position) VALUES (?, ?, ?, ?, ?)',
                        [firstName, lastName, email, hashedPassword, position],
                        (err, results) => {
                            if (err) {
                                console.error('Database insert error:', err);
                                return res.status(500).json({ message: 'Server error during user registration' });
                            }
                            console.log('User registered successfully:', email);
                            res.status(201).json({ message: 'User registered successfully' });
                        }
                    );
                } catch (error) {
                    console.error('Error during password hashing:', error);
                    res.status(500).json({ message: 'Server error during password hashing' });
                }
            });
        } else {
            // Proceed with user registration for non-admin users
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                console.log('Password hashed successfully');
                db.query(
                    'INSERT INTO users (first_name, last_name, email, user_password, position) VALUES (?, ?, ?, ?, ?)',
                    [firstName, lastName, email, hashedPassword, position],
                    (err, results) => {
                        if (err) {
                            console.error('Database insert error:', err);
                            return res.status(500).json({ message: 'Server error during user registration' });
                        }
                        console.log('User registered successfully:', email);
                        res.status(201).json({ message: 'User registered successfully' });
                    }
                );
            } catch (error) {
                console.error('Error during password hashing:', error);
                res.status(500).json({ message: 'Server error during password hashing' });
            }
        }
    });
});


// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Received login request:', req.body);

    // Check if the user exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error('Database query error during login:', err);
            return res.status(500).json({ message: 'Server error during login' });
        }
        if (results.length === 0) {
            console.log('User not found:', email);
            return res.status(400).json({ message: 'Incorrect email or password' });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.user_password);
        if (!isPasswordValid) {
            console.log('Invalid password for user:', email);
            return res.status(400).json({ message: 'Incorrect email or password' });
        }

        // Return user details including position
        res.status(200).json({ user: { email: user.email, position: user.position } });
    });
});

// Create project endpoint
app.post('/api/create_project', (req, res) => {
    const { project_name, project_location, project_description } = req.body;
    console.log('Received project creation request:', { project_name, project_location, project_description });
    if (!project_name || !project_location) {
        return res.status(400).json({ message: 'Project name and location are required' });
    }
    const query = 'INSERT INTO projects (project_name, project_location, project_description) VALUES (?, ?, ?)';
    db.query(query, [project_name, project_location, project_description || ''], (err, results) => {
        if (err) {
            console.error('Database insert error:', err);
            return res.status(500).json({ message: 'Server error during project creation', error: err });
        }
        console.log('Project created successfully:', results);
        res.status(201).json({ message: 'Project created successfully', projectId: results.insertId });
    });
});

    // Fetch projects endpoint
    app.get('/api/projects', (req, res) => {
        const query = 'SELECT project_id, project_name, project_location, project_description, project_completion, created_at FROM projects';
        db.query(query, (err, results) => {
            if (err) {
                console.error('Database fetch error:', err);
                return res.status(500).json({ message: 'Server error during project fetch', error: err });
            }
            res.status(200).json(results);
        });
    });

    
    // Delete project endpoint
    app.delete('/api/delete_project/:projectId', (req, res) => {
        const projectId = req.params.projectId;
        const query = 'DELETE FROM projects WHERE project_id = ?';

        db.query(query, [projectId], (err, result) => {
            if (err) {
                console.error('Error deleting project:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Project not found' });
            }

            res.status(200).json({ message: 'Project deleted successfully' });
        });
    });

    // Update project endpoint
    app.put('/api/update_project/:projectId', (req, res) => {
        const projectId = req.params.projectId;
        const { project_name, project_location, project_description } = req.body;
        const query = 'UPDATE projects SET project_name = ?, project_location = ?, project_description = ? WHERE project_id = ?';

        db.query(query, [project_name, project_location, project_description, projectId], (err, result) => {
            if (err) {
                console.error('Error updating project:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Project not found' });
            }

            res.status(200).json({ message: 'Project updated successfully' });
        });
    });

// Archive project route
app.put('/api/archive_project/:id', async (req, res) => {
    const projectId = req.params.id;
    const { group } = req.body;

    try {
        const query = 'UPDATE projects SET project_group = ? WHERE project_id = ?';
        const values = [group, projectId];

        db.query(query, values, (err, result) => {
            if (err) {
                console.error('Database update error:', err);
                return res.status(500).json({ message: 'Internal server error', error: err });
            }

            if (result.affectedRows === 0) {
                console.log(`No project found with ID: ${projectId}`);
                return res.status(404).json({ message: 'Project not found' });
            }

            console.log(`Project with ID: ${projectId} archived successfully`);
            res.json({ message: 'Project archived successfully' });
        });
    } catch (error) {
        console.error('Error archiving project:', error);
        res.status(500).json({ message: 'Internal server error', error });
    }
});
// Fetch project details endpoint
app.get('/api/project/:id', (req, res) => {
    const projectId = req.params.id;
    const query = 'SELECT project_name, project_description FROM projects WHERE project_id = ?';
    db.query(query, [projectId], (err, results) => {
        if (err) {
            console.error('Database fetch error:', err);
            return res.status(500).json({ message: 'Server error during project fetch', error: err });
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Project not found' });
        }
        res.status(200).json(results[0]);
    });
});
// Create a group
app.post('/api/proj_groups', (req, res) => {
    const { project_id, name } = req.body;
    console.log('Received request to create group:', req.body); // Debug log

    if (!project_id || !name) {
        console.log('Project ID or group name is missing'); // Debug log
        return res.status(400).json({ message: 'Project ID and group name are required' });
    }

    // Use backticks to escape the `groups` table name
    const query = 'INSERT INTO proj_groups (project_id, name) VALUES (?, ?)';
    db.query(query, [project_id, name], (err, results) => {
        if (err) {
            console.error('Database insert error:', err); // Debug log
            return res.status(500).json({ message: 'Server error during group creation', error: err });
        }
        console.log('Group created successfully:', results); // Debug log
        res.status(201).json({ id: results.insertId, message: 'Group created successfully' });
    });
});

    // Add a column to a group
    app.post('/api/group_columns', (req, res) => {
        const { group_id, name, type } = req.body;
        if (!group_id || !name || !type) {
            return res.status(400).json({ message: 'Group ID, column name, and type are required' });
        }

        // Insert the column without checking for duplicates
        const query = 'INSERT INTO group_columns (group_id, name, type) VALUES (?, ?, ?)';
        db.query(query, [group_id, name, type], (err, results) => {
            if (err) {
                console.error('Database insert error:', err);
                return res.status(500).json({ message: 'Server error during column creation', error: err });
            }
            res.status(201).json({ id: results.insertId, message: 'Column added successfully' });
        });
    });

    // Add a row to a group
    app.post('/api/group_rows', (req, res) => {
        const { group_id } = req.body;
        if (!group_id) {
            return res.status(400).json({ message: 'Group ID is required' });
        }
        const query = 'INSERT INTO group_rows (group_id) VALUES (?)';
        db.query(query, [group_id], (err, results) => {
            if (err) {
                console.error('Database insert error:', err);
                return res.status(500).json({ message: 'Server error during row creation', error: err });
            }
            res.status(201).json({ id: results.insertId, message: 'Row added successfully' });
        });
    });

    // Save cell data
    app.post('/api/cell_data', (req, res) => {
        const { row_id, column_id, field, value } = req.body; // Include field in the request body
        console.log('Received cell data save request:', { row_id, column_id, field, value }); // Debug log

        if (!row_id || !column_id || !field || value === undefined) {
            console.error('Missing parameters:', { row_id, column_id, field, value }); // Debug log
            return res.status(400).json({ message: 'Row ID, column ID, field, and value are required' });
        }

        const query = `
            INSERT INTO cell_data (row_id, column_id, field, value)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE value = VALUES(value), field = VALUES(field)
        `;
        db.query(query, [row_id, column_id, field, value], (err, results) => {
            if (err) {
                console.error('Database insert/update error:', err); // Debug log
                return res.status(500).json({ message: 'Server error during cell data save', error: err });
            }
            console.log('Cell data saved successfully:', results); // Debug log
            res.status(200).json({ message: 'Cell data saved successfully' });
        });
    });







    // Fetch all groups for a project
    app.get('/api/project/:projectId/groups', (req, res) => {
        const projectId = req.params.projectId;
        const query = 'SELECT id, name FROM proj_groups WHERE project_id = ?';
        db.query(query, [projectId], (err, results) => {
            if (err) {
                console.error('Database fetch error:', err);
                return res.status(500).json({ message: 'Server error during groups fetch', error: err });
            }
            res.status(200).json(results);
        });
    });

    // Fetch all rows for a group
    app.get('/api/group/:groupId/rows', (req, res) => {
        const groupId = req.params.groupId;
        const query = 'SELECT * FROM group_rows WHERE group_id = ?';
        db.query(query, [groupId], (err, results) => {
            if (err) {
                console.error('Database fetch error:', err);
                return res.status(500).json({ message: 'Server error during rows fetch', error: err });
            }
            res.status(200).json(results);
        });
    });

    // Endpoint to delete a group
    app.delete('/api/group/:groupId', (req, res) => {
        const groupId = req.params.groupId;
        // First, delete the associated rows and columns (if any)
        const deleteRowsQuery = 'DELETE FROM group_rows WHERE group_id = ?';
        const deleteColumnsQuery = 'DELETE FROM group_columns WHERE group_id = ?';
        const deleteGroupQuery = 'DELETE FROM proj_groups WHERE id = ?';
        db.query(deleteRowsQuery, [groupId], (err, results) => {
            if (err) {
                console.error('Database delete error (rows):', err);
                return res.status(500).json({ message: 'Server error during rows deletion', error: err });
            }
            db.query(deleteColumnsQuery, [groupId], (err, results) => {
                if (err) {
                    console.error('Database delete error (columns):', err);
                    return res.status(500).json({ message: 'Server error during columns deletion', error: err });
                }
                db.query(deleteGroupQuery, [groupId], (err, results) => {
                    if (err) {
                        console.error('Database delete error (group):', err);
                        return res.status(500).json({ message: 'Server error during group deletion', error: err });
                    }
                    res.status(200).json({ message: 'Group deleted successfully' });
                });
            });
        });
    });

    // Endpoint to delete a row
    app.delete('/api/group_row/:rowId', (req, res) => {
        const rowId = req.params.rowId;

        const deleteRowQuery = 'DELETE FROM group_rows WHERE id = ?';
        const deleteCellDataQuery = 'DELETE FROM cell_data WHERE row_id = ?';

        db.query(deleteCellDataQuery, [rowId], (err, results) => {
            if (err) {
                console.error('Database delete error (cell data):', err);
                return res.status(500).json({ message: 'Server error during cell data deletion', error: err });
            }

            db.query(deleteRowQuery, [rowId], (err, results) => {
                if (err) {
                    console.error('Database delete error (row):', err);
                    return res.status(500).json({ message: 'Server error during row deletion', error: err });
                }

                res.status(200).json({ message: 'Row deleted successfully' });
            });
        });
    });

    // Fetch all columns for a group
    app.get('/api/group/:groupId/columns', (req, res) => {
    const groupId = req.params.groupId;
    const query = 'SELECT id, name, type FROM group_columns WHERE group_id = ?';
    db.query(query, [groupId], (err, results) => {
        if (err) {
            console.error('Database fetch error:', err);
            return res.status(500).json({ message: 'Server error during columns fetch', error: err });
        }
        res.status(200).json(results);
        });
    });

    // Fetch all cell data for a group
    app.get('/api/group/:groupId/cell_data', (req, res) => {
        const groupId = req.params.groupId;
        const query = `
            SELECT cd.row_id, cd.column_id, cd.value 
            FROM cell_data cd
            JOIN group_rows gr ON cd.row_id = gr.id
            WHERE gr.group_id = ?
        `;
        db.query(query, [groupId], (err, results) => {
            if (err) {
                console.error('Database fetch error:', err);
                return res.status(500).json({ message: 'Server error during cell data fetch', error: err });
            }
            res.status(200).json(results);
        });
    });
    // Endpoint to update column name
    app.put('/api/group_column/:columnId', (req, res) => {
        const columnId = req.params.columnId;
        const { name } = req.body;

        if (!name) {
            return res.status(400).json({ message: 'Column name is required' });
        }

        const query = 'UPDATE group_columns SET name = ? WHERE id = ?';
        db.query(query, [name, columnId], (err, results) => {
            if (err) {
                console.error('Database update error:', err);
                return res.status(500).json({ message: 'Server error during column name update', error: err });
            }

            res.status(200).json({ message: 'Column name updated successfully' });
        });
    });

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});