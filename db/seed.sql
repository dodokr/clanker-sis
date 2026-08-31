INSERT INTO users (name, email, password_hash) VALUES
    ('John', 'john.doe@gmai.com',
        '$2a$10$jsH32XiJcn8CdrxPczdKI.LLAekLtIk7Gm6/fYVEq3fgqI/DUo.Ji'), -- 123
    ('Alice', 'alice@yahoo.com',
        '$2a$10$CEi9pCZhCsmr3cPbGh8sru6M1eI18vIY02/Zj4y4kfEaQxhuZx4pa'); -- 321

INSERT INTO organizations (name) VALUES
    ('Foo Corp'),
    ('Bar Org');

INSERT INTO user_org_membership (user_id, org_id, valid_from) VALUES
    ((SELECT id FROM users WHERE email = 'john.doe@gmai.com'), (SELECT id FROM organizations WHERE name = 'Foo Corp'), NOW()),
    ((SELECT id FROM users WHERE email = 'alice@yahoo.com'), (SELECT id FROM organizations WHERE name = 'Bar Org'), NOW());
