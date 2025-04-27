const app = require('./app')
const requestLogger = require('./src/middlewares/logging')
const proxyjoke = require('./src/middlewares/proxy')

app.use(requestLogger());
app.use(proxyjoke);

app.listen(process.env.PORT || 3000, (req,res)=>{
    console.log(`proxy server listening`)
});