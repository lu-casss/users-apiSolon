const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

const users = [
  {
    LastName: "Solon",
    FirstName: "Lucas",
    Email: "Lucas@email.com",
    Password: "12345"
  },
  {
    LastName: "name",
    FirstName: "namename",
    Email: "name@email.com",
    Password: "nameemail1"
  },
  {
    LastName: "email",
    FirstName: "lastemail",
    Email: "email@name.com",
    Password: "2444123"
  }
];

app.get("/", (req, res) => {
  res.send("Users API is running!");
});

app.get("/users", (req, res) => {
  res.json(users);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});