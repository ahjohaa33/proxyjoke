const app = require('./app')
const requestLogger = require('./src/middlewares/logging')
const proxyjoke = require('./src/middlewares/proxy')

app.use(requestLogger());
app.use(proxyjoke);

const Port = process.env.PORT || 4000;

app.listen(Port, (req,res)=>{
    console.log(`proxy server listening on PORT: ${Port}`)
});