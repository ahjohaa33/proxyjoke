const app = require('./app')
const log = require('./src/middlewares/logging')
const proxy = require('./src/middlewares/proxy')

app.use(log);
app.get('/proxy', proxy);

app.listen(process.env.PORT || 3000, (req,res)=>{
    console.log(`proxy server listening`)
});