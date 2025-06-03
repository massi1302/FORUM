# Academic Discussion Forum

A sophisticated platform designed to facilitate academic discussions and knowledge sharing among students, researchers, and educators.

## Features

- **Structured Discussions**: Organize conversations by academic topics and disciplines
- **User Authentication**: Secure login and registration system
- **Thread Management**: Create, edit, and moderate discussion threads
- **Interactive Responses**: Reply to threads and engage in academic discourse
- **Voting System**: Highlight valuable contributions through community voting
- **Tag System**: Categorize discussions for easy navigation
- **Search Functionality**: Find relevant discussions and resources
- **Responsive Design**: Access the forum on any device

## Technical Stack

- **Backend**: Go with Gin framework
- **Database**: MySQL with GORM
- **Authentication**: JWT-based authentication
- **Frontend**: HTML, CSS, JavaScript

## Getting Started

1. Clone the repository
2. Set up environment variables in `.env`
3. Install dependencies
4. Run the application:
   ```bash
   go run main.go
   ```

## Environment Variables

Create a `.env` file with the following variables:
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=forum_educatif
JWT_SECRET=your_jwt_secret
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the repository or contact the maintainers.