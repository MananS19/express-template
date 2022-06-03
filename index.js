require("./config/global");
const port = process.env.PORT || 3000;
const cors = require("cors");

const connect = require("./config/db");
connect();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

app.use("/user", require("./routes/UserRoute"));

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
