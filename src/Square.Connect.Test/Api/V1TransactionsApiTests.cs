/* 
 * Square Connect API
 *
 * Client library for accessing the Square Connect APIs
 *
 * OpenAPI spec version: 2.0
 * Contact: developers@squareup.com
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
    ///  Class for testing V1TransactionsApi
    /// </summary>
    /// <remarks>
    /// This file is automatically generated by Swagger Codegen.
    /// Please update the test case below to test the API endpoint.
    /// </remarks>
    [TestFixture]
    public class V1TransactionsApiTests
    {
        private V1TransactionsApi instance;

        /// <summary>
        /// Setup before each unit test
        /// </summary>
        [SetUp]
        public void Init()
        {
            instance = new V1TransactionsApi();
        }

        /// <summary>
        /// Clean up after each unit test
        /// </summary>
        [TearDown]
        public void Cleanup()
        {

        }

        /// <summary>
        /// Test an instance of V1TransactionsApi
        /// </summary>
        [Test]
        public void InstanceTest()
        {
            // TODO uncomment below to test 'IsInstanceOfType' V1TransactionsApi
            //Assert.IsInstanceOfType(typeof(V1TransactionsApi), instance, "instance is a V1TransactionsApi");
        }

        
        /// <summary>
        /// Test CreateRefund
        /// </summary>
        [Test]
        public void CreateRefundTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //V1CreateRefundRequest body = null;
            //var response = instance.CreateRefund(locationId, body);
            //Assert.IsInstanceOf<V1Refund> (response, "response is V1Refund");
        }
        
        /// <summary>
        /// Test ListBankAccounts
        /// </summary>
        [Test]
        public void ListBankAccountsTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //var response = instance.ListBankAccounts(locationId);
            //Assert.IsInstanceOf<List<V1BankAccount>> (response, "response is List<V1BankAccount>");
        }
        
        /// <summary>
        /// Test ListOrders
        /// </summary>
        [Test]
        public void ListOrdersTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string order = null;
            //int? limit = null;
            //var response = instance.ListOrders(locationId, order, limit);
            //Assert.IsInstanceOf<List<V1Order>> (response, "response is List<V1Order>");
        }
        
        /// <summary>
        /// Test ListPayments
        /// </summary>
        [Test]
        public void ListPaymentsTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string order = null;
            //string beginTime = null;
            //string endTime = null;
            //int? limit = null;
            //var response = instance.ListPayments(locationId, order, beginTime, endTime, limit);
            //Assert.IsInstanceOf<List<V1Payment>> (response, "response is List<V1Payment>");
        }
        
        /// <summary>
        /// Test ListRefunds
        /// </summary>
        [Test]
        public void ListRefundsTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string order = null;
            //string beginTime = null;
            //string endTime = null;
            //int? limit = null;
            //var response = instance.ListRefunds(locationId, order, beginTime, endTime, limit);
            //Assert.IsInstanceOf<List<V1Refund>> (response, "response is List<V1Refund>");
        }
        
        /// <summary>
        /// Test ListSettlements
        /// </summary>
        [Test]
        public void ListSettlementsTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string order = null;
            //string beginTime = null;
            //string endTime = null;
            //int? limit = null;
            //string status = null;
            //var response = instance.ListSettlements(locationId, order, beginTime, endTime, limit, status);
            //Assert.IsInstanceOf<List<V1Settlement>> (response, "response is List<V1Settlement>");
        }
        
        /// <summary>
        /// Test RetrieveBankAccount
        /// </summary>
        [Test]
        public void RetrieveBankAccountTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string bankAccountId = null;
            //var response = instance.RetrieveBankAccount(locationId, bankAccountId);
            //Assert.IsInstanceOf<V1BankAccount> (response, "response is V1BankAccount");
        }
        
        /// <summary>
        /// Test RetrieveOrder
        /// </summary>
        [Test]
        public void RetrieveOrderTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string orderId = null;
            //var response = instance.RetrieveOrder(locationId, orderId);
            //Assert.IsInstanceOf<V1Order> (response, "response is V1Order");
        }
        
        /// <summary>
        /// Test RetrievePayment
        /// </summary>
        [Test]
        public void RetrievePaymentTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string paymentId = null;
            //var response = instance.RetrievePayment(locationId, paymentId);
            //Assert.IsInstanceOf<V1Payment> (response, "response is V1Payment");
        }
        
        /// <summary>
        /// Test RetrieveSettlement
        /// </summary>
        [Test]
        public void RetrieveSettlementTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string settlementId = null;
            //var response = instance.RetrieveSettlement(locationId, settlementId);
            //Assert.IsInstanceOf<V1Settlement> (response, "response is V1Settlement");
        }
        
        /// <summary>
        /// Test UpdateOrder
        /// </summary>
        [Test]
        public void UpdateOrderTest()
        {
            // TODO uncomment below to test the method and replace null with proper value
            //string locationId = null;
            //string orderId = null;
            //V1UpdateOrderRequest body = null;
            //var response = instance.UpdateOrder(locationId, orderId, body);
            //Assert.IsInstanceOf<V1Order> (response, "response is V1Order");
        }
        
    }

}
