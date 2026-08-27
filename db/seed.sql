INSERT INTO users (name, email, password_hash) VALUES
    ('John', 'john.doe@gmai.com', 'hash'),
    ('Alice', 'alice@yahoo.com', 'haaaaash');

INSERT INTO organizations (name) VALUES
    ('Foo Corp'),
    ('Bar Org');

INSERT INTO user_org_membership (user_id, org_id, valid_from) VALUES
    ((SELECT id FROM users WHERE email = 'john.doe@gmai.com'), (SELECT id FROM organizations WHERE name = 'Foo Corp'), NOW()),
    ((SELECT id FROM users WHERE email = 'alice@yahoo.com'), (SELECT id FROM organizations WHERE name = 'Bar Org'), NOW());
