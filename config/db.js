const connect = () => {
  mongoose.connect(process.env.DB_CONNECTION, (err) => {
    if (err) {
      console.log(err);
    } else {
      console.log("connected to db");
    }
  });
};
module.exports = connect;
