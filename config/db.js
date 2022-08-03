require("dotenv").config();

const mongoose = require("mongoose");
const mongooseCS = require("mongoose");

const { DB_ENV, COSMOSDB_USER, COSMOSDB_PASSWORD, COSMOSDB_URI, MONGODB_URI } =
  process.env;

if (DB_ENV === "AZURE") {
  mongooseCS
    .connect(COSMOSDB_URI, {
      auth: {
        username: COSMOSDB_USER,
        password: COSMOSDB_PASSWORD,
      },
      useNewUrlParser: true,
      useUnifiedTopology: true,
      retryWrites: false,
    })
    .then(() => console.log("Connection to CosmosDB successful"))
    .catch((err) => console.error(err));
} else {
  mongoose
    .connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log("Mongo DB Connected");
    })
    .catch((error) => console.log(error));
}
