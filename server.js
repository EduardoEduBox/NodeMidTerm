import express from "express";
import path from "path";
const server = express();

import urlsRouter from "./routes/urls.js";
import authRouter from "./routes/auth.js";
import { getEmail } from "./controllers/auth.js"; 

import cookieSession from "cookie-session";

server.set("view engine", "ejs");
server.set("views", path.join(path.resolve(), "views"));
server.use(express.urlencoded({ extended: true }));
server.use(express.json());
server.use(cookieSession({
  name: 'session',
  keys: ['key1', 'key2']
}));
server.use((req, res, next) => {
  res.locals.login = req.session.login;
  if(req.session.userId) {
    res.locals.email = getEmail(req.session.userId);
  }
  next();
});

server.use("/urls", urlsRouter);

server.use("/", authRouter);

server.get("/", (req, res) => {
  res.render("home", {login: req.session.login});
});

export default server;
