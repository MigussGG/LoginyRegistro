const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();

const mongoose = require('mongoose');
const User = require('./user');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const mongo_uri = 'mongodb://127.0.0.1:27017/Registros';


mongoose.connect(mongo_uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log(`Successfully connected to ${mongo_uri}`);
}).catch((error) => {
  console.error('Error connecting to database:', error);
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const user = new User({ username, password });

  user.save()
    .then(() => {
      res.status(200).send('USUARIO REGISTRADO');
    })
    .catch((err) => {
      res.status(500).send('ERROR AL REGISTRAR USUARIO');
    });
});

app.post('/authenticate', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.status(500).send('EL USUARIO NO EXISTE');
      } else {
        const result = user.isCorrectPassword(password);
        if (result) {
          res.status(200).send('USUARIO AUTENTICADO CORRECTAMENTE');
        } else {
          res.status(500).send('USUARIO Y/O CONTRASEÑA INCORRECTA');
        }
      }
    })
    .catch(err => {
      res.status(500).send('ERROR AL BUSCAR USUARIO');
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

module.exports = app;
