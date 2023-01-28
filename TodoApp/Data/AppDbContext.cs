﻿using Microsoft.EntityFrameworkCore;
using TodoApp.Models;

namespace TodoApp.Data
{
    public class AppDbContext:DbContext
    {
        public virtual DbSet<Item> Items { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options)
            :base(options)
        {}
    }
}