using event_test.Data;
using event_test.Models;
using event_test.VModels;
using jwt;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<ApplicationDbContext>(
    opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddScoped<IRepositoryEvent,RepositoryEvent>();
builder.Services.AddScoped<IRepository<Booking, VMBooking>, RepositoryBooking>();
Seed.Setting(builder);
var app = builder.Build();
await Seed.AddRoll(app.Services, new List<string> { "User", "Admin", "Employee" }); //Add this line to add rolles
await Seed.AddAdmin(app.Services, builder.Configuration["EmailSender:UserName"]!); //Add this line to add admin user
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
