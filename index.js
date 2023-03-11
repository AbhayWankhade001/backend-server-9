import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import connect from './database/conn.js';
import router from './router/route.js';
import bodyParser from 'body-parser'; 
import router2 from './router/router2.js';
import "./router/config.js"
const app = express();

/** middlewares */
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));
app.disable('x-powered-by'); // less hackers know about our stack

router.use(bodyParser.json());
const port = process.env.PORT || 8080;

// Add config variable declaration
const config = process.env.CONFIG ? JSON.parse(Buffer.from(process.env.CONFIG, 'base64').toString('ascii')) : {};

/** Https get req */

app.get('/', (req,res)=>{
  res.status(201).json("home get request")
})

/** api routes */
app.use('/api' , router )
app.use("/api", router2);

/** start server */
connect().then(()=>{
  try {
    app.listen(port, () =>{
      console.log(`server connected to https://localhost:${port}`);
    });
  } catch (error) {
    console.log('cannot connect to the server')
  }
}).catch(error => {
  console.log("invalid database connection.... !")
})

// Use config variables

export default app;