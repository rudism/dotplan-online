create table users (
  email text primary key,
  password text not null,
  token text,
  token_expires timestamp,
  pw_token text,
  pw_token_expires timestamp,
  verified boolean not null default false,
  created timestamp not null default current_timestamp,
  updated timestamp
);
