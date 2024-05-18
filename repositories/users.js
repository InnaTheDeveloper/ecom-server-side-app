const fs = require("fs");
const crypto = require("crypto");
const util = require("util");
const Repository = require("./repository");

const scrypt = util.promisify(crypto.scrypt);

class UsersRepository extends Repository {
  async create(attrs) {
    attrs.id = this.randomId();
    const salt = crypto.randomBytes(8).toString("hex");
    const buf = await scrypt(attrs.password, salt, 64);
    const records = await this.getAll();
    const record = {
      ...attrs,
      password: `${buf.toString("hex")}.${salt}`,
    };
    records.push(record);

    await this.writeAll(records);
    return record;
  }
  async comparePasswords(saved, supplied) {
    // saved -> password savid in our database 'hashed.salt'
    //supplied -> password given to us by a user trying sign in
    // const result = saved.split('.');
    // const hashed = result[0];
    // const salt = result[1]

    const [hashed, salt] = saved.split(".");
    const hashedSuppliedBuf = await scrypt(supplied, salt, 64);

    return hashed === hashedSuppliedBuf.toString("hex");
  }
}

module.exports = new UsersRepository("users.json");

// module.exports = UsersRepository;

//another file...
// const UsersRepository = require('./users')
// const repo = new UsersRepository('users.json')

// yet another file...
// const UsersRepository = require('./users')
// const repo = new UsersRepository('user.json') - we make a small typo

// it will end up creating two different sets of users for your application and it will be a challenge to find this bug

// instead we are going to export the instance of a class (not the class itself)
