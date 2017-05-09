/* 
 * Square Connect API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 2.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using RestSharp;
using NUnit.Framework;

using Square.Connect.Client;
using Square.Connect.Api;
using Square.Connect.Model;

namespace Square.Connect.Test
{
    /// <summary>
    ///  Class for testing CustomerApi
    /// </summary>
    /// <remarks>
    /// This file is automatically generated by Swagger Codegen.
    /// Please update the test case below to test the API endpoint.
    /// </remarks>
    [TestFixture]
    public class CustomerApiTests
    {
        private CustomerApi instance;

        /// <summary>
        /// Setup before each unit test
        /// </summary>
        [SetUp]
        public void Init()
        {
            instance = new CustomerApi();
        }

        /// <summary>
        /// Clean up after each unit test
        /// </summary>
        [TearDown]
        public void Cleanup()
        {

        }

        /// <summary>
        /// Test an instance of CustomerApi
        /// </summary>
        [Test]
        public void InstanceTest()
        {
            // TODO uncomment below to test 'IsInstanceOfType' CustomerApi
            //Assert.IsInstanceOfType(typeof(CustomerApi), instance, "instance is a CustomerApi");
        }

        
        /// <summary>
        /// Test CreateCustomer
        /// </summary>
        [Test]
        public void CreateCustomerTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string authorization = null;
            //CreateCustomerRequest body = null;
            //var response = instance.CreateCustomer(authorization, body);
            //Assert.IsInstanceOf<CreateCustomerResponse> (response, "response is CreateCustomerResponse");
        }
        
        /// <summary>
        /// Test DeleteCustomer
        /// </summary>
        [Test]
        public void DeleteCustomerTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string authorization = null;
            //string customerId = null;
            //var response = instance.DeleteCustomer(authorization, customerId);
            //Assert.IsInstanceOf<DeleteCustomerResponse> (response, "response is DeleteCustomerResponse");
        }
        
        /// <summary>
        /// Test ListCustomers
        /// </summary>
        [Test]
        public void ListCustomersTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string authorization = null;
            //string cursor = null;
            //var response = instance.ListCustomers(authorization, cursor);
            //Assert.IsInstanceOf<ListCustomersResponse> (response, "response is ListCustomersResponse");
        }
        
        /// <summary>
        /// Test RetrieveCustomer
        /// </summary>
        [Test]
        public void RetrieveCustomerTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string authorization = null;
            //string customerId = null;
            //var response = instance.RetrieveCustomer(authorization, customerId);
            //Assert.IsInstanceOf<RetrieveCustomerResponse> (response, "response is RetrieveCustomerResponse");
        }
        
        /// <summary>
        /// Test UpdateCustomer
        /// </summary>
        [Test]
        public void UpdateCustomerTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string authorization = null;
            //string customerId = null;
            //UpdateCustomerRequest body = null;
            //var response = instance.UpdateCustomer(authorization, customerId, body);
            //Assert.IsInstanceOf<UpdateCustomerResponse> (response, "response is UpdateCustomerResponse");
        }
        
    }

}